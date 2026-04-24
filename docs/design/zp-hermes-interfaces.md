# ZeroPoint × Hermes Integration Interfaces

Four typed seams where ZeroPoint governs Hermes-style agent systems. Each seam has a specific Hermes chokepoint (confirmed by the 2026-04-24 subsystem audit), a fixed wire shape, a receipt class, and a lifecycle. The interfaces below are binding contracts — implementations on either side must match these signatures exactly.

The interfaces are named for what they carry, not which side speaks first. Every one is bidirectional: the agent proposes, ZeroPoint disposes.

---

## 1 · `ZPMemoryProvider`

**Purpose.** Hermes proposes; ZeroPoint classifies, policy-checks, signs, persists. Hermes sees back only the approved record or a denial.

**Chokepoint.** `tools/memory_tool.py:463` — `memory_tool()` accepts an optional `store` parameter. Replace Hermes's file-backed `MemoryStore` with a `ZPMemoryProvider` implementation that RPCs to ZeroPoint.

**Wire contract (agent-side Python adapter).**

```python
class ZPMemoryProvider:
    def propose(self, op: MemoryOp) -> MemoryResult: ...
    def read(self, query: MemoryQuery) -> list[MemoryEntry]: ...

@dataclass
class MemoryOp:
    action: Literal["add", "replace", "remove"]
    target: Literal["MEMORY", "USER", str]   # str for scoped domains
    content: str
    proposed_at: int                          # ms since epoch
    thread_id: str
    run_id: str

@dataclass
class MemoryResult:
    status: Literal["accepted", "denied", "quarantined"]
    receipt_id: str | None                    # present iff accepted
    reason: str | None                        # present iff denied or quarantined
    entry: MemoryEntry | None                 # the persisted record (for reads & accepts)
```

**ZP-side trait (Rust).**

```rust
pub trait MemoryProvider {
    fn propose(&mut self, op: &MemoryOp, ctx: &PolicyContext)
        -> Result<MemoryOutcome, MemoryError>;
    fn read(&self, query: &MemoryQuery, ctx: &PolicyContext)
        -> Result<Vec<MemoryEntry>, MemoryError>;
}
```

**Lifecycle.**

```
proposed  ──(policy auto-approve)──►  accepted  ──►  signed receipt emitted
          ──(policy hold)──►  quarantined  ──(human review)──►  accepted | denied
          ──(policy reject)──►  denied
```

**Receipt emitted.** `ClaimType::MemoryCommit` with `ClaimMetadata::Memory { action, target, entry_hash, reviewer }`. Hash of the entry content lives in the receipt; the content itself lives in the memory store. The audit chain proves *that* a memory was committed and *what* its content was, without making the chain a blob store.

**Failure modes.**
- ZP unreachable → adapter returns `MemoryResult::status="denied"` with `reason="provider_unreachable"`. Hermes must handle denial as first-class; not a fatal error.
- Quarantined proposals → Hermes sees `status="quarantined"` and must not assume the memory exists on read-back until review completes.
- Latency budget → auto-approve path ≤ 50 ms; quarantine path returns immediately (Hermes does not block on human review).

**Integration cost.** Clean swap. ZP reimplements `MemoryStore`; Hermes code unchanged.

---

## 2 · `ZPBrowserExecutionEnvelope`

**Purpose.** A browser-enabled run does not have ambient browser access. It has a scoped, time-boxed capability envelope signed by ZeroPoint, consumed by each `browser_*` tool invocation.

**Chokepoint.** `hermes_cli/plugins.py` — register a `pre_tool_call_block_message` plugin. On every dispatch of a tool whose name starts with `browser_`, the plugin checks whether the envelope covers the proposed action; block-with-message if not.

**Envelope shape.**

```rust
pub struct BrowserExecutionEnvelope {
    pub envelope_id: Uuid,
    pub issued_at: i64,
    pub expires_at: i64,
    pub thread_id: String,
    pub run_id: String,

    /// Origin allowlist. Entries may be exact hosts or glob patterns
    /// (e.g., `*.example.com`). Empty = deny all.
    pub origins: Vec<String>,

    /// Action classes this envelope permits. Subset of:
    /// navigate | click | type | scroll | snapshot | vision | console
    pub actions: Vec<BrowserAction>,

    /// Maximum wall-clock budget, in seconds, across the run.
    pub budget_seconds: u32,

    /// Ed25519 signature over the canonical serialization, by an
    /// identity key with BrowserGrant authority.
    pub signature: [u8; 64],
    pub issuer_key: [u8; 32],
}
```

**Issuance.** `POST /api/v1/envelopes/browser` — issues an envelope bound to a `thread_id + run_id + policy_context`. The AG-UI proxy obtains one at run start and forwards it to the bridge as a header (`X-ZP-Envelope: <base64>`); the bridge injects it into the Hermes subprocess env as `ZP_BROWSER_ENVELOPE`; the plugin reads it.

**Consumption.** Each `browser_*` dispatch carries args (URL for navigate, selector for click, etc.). Plugin:
1. Decodes and verifies the envelope signature against ZP's genesis-rooted key set.
2. Checks `expires_at`, `origins` vs. target URL, `actions` vs. the tool name.
3. On pass: emits a `ClaimType::BrowserAction` receipt with envelope ref + args-hash; allows dispatch.
4. On fail: returns a block message naming the violated constraint; emits a `ClaimType::BrowserRefusal` receipt.

**Receipt types.**
- `BrowserAction` — per allowed dispatch, with args-hash.
- `BrowserRefusal` — per blocked dispatch, with constraint ID (origin / action / budget / expired).
- `BrowserEnvelopeIssued` — once per run, at envelope issuance.
- `BrowserEnvelopeExpired` — once per envelope, at expiry or revocation.

**Failure modes.**
- Envelope signature invalid → block, log `BrowserRefusal { reason: invalid_signature }`, tear down the run.
- Envelope expired mid-run → subsequent dispatches blocked with `expired`; ZP never reissues silently.
- Envelope constraints too tight to complete work → Hermes's natural behavior is to fail the task and report; no policy-hole shortcut.

**Integration cost.** Clean swap via existing plugin hook. Adds one new ZP endpoint (`/envelopes/browser`) and one receipt family.

---

## 3 · `ZPSkillReceipt`

**Purpose.** A skill (a persistent named behavior that extends what Hermes knows how to do) is not an event — it is a new signed artifact. Skills have their own wire on the abacus, distinct from tool-invocation beads.

**Chokepoint.** Hermes's `skill_manage`, `skill_create`, and related tools — find the write path and route proposals through `ZPSkillReceipt` rather than directly to `~/.hermes/skills/`.

**Lifecycle (state machine).**

```
                 ┌────► observed-effective  ─────┐
 proposed  ──────┤                               ├──► verification-pending  ──► signed
                 └────► ignored                  │
                                                 │
 signed   ──► superseded (by a newer skill)  ────┘
          ──► revoked    (by operator or policy)
```

Transitions:
- `proposed` → `observed-effective` — skill produced a useful outcome in N runs (threshold policy-configurable; default N=3).
- `proposed` → `ignored` — skill was never used after proposal for a retention window; cleared.
- `observed-effective` → `verification-pending` — auto-promotion after effectiveness threshold; enters review queue.
- `verification-pending` → `signed` — operator signs; the skill now belongs to the substrate.
- `signed` → `revoked` — operator or policy (e.g., `HarmPrincipleRule` triggered in retrospect).
- `signed` → `superseded` — a newer skill replaces it; old skill retains chain visibility but is inactive.

**Receipt shape.**

```rust
pub struct SkillReceipt {
    pub skill_id: Uuid,                     // stable across state transitions
    pub state: SkillState,                  // proposed | observed-effective | ...
    pub name: String,
    pub domain: String,                     // e.g., "terminal", "browser", "research"
    pub proposed_by: String,                // agent identity that proposed it
    pub proposed_at: i64,
    pub content_hash: [u8; 32],             // hash of the skill body (code / prompt / strategy)
    pub parent_skill: Option<Uuid>,         // for supersession chains
    pub evidence_count: u32,                // runs that observed this skill effective
    pub reviewer_signature: Option<ReviewerSig>,  // present iff state ≥ signed
}
```

Skills have their own domain wire on the abacus (`skill:proposed:<name>`, `skill:signed:<name>`). Bead zero per skill is the `proposed` receipt; the chain walks its state transitions until `revoked` or `superseded`.

**Query interface.**
- `GET /api/v1/skills` — list, filterable by state.
- `GET /api/v1/skills/:skill_id` — single skill with full transition history.
- `POST /api/v1/skills/:skill_id/sign` — operator action; transitions `verification-pending` → `signed` and stamps `reviewer_signature`.
- `POST /api/v1/skills/:skill_id/revoke` — transitions `signed` → `revoked`; Hermes stops loading this skill on next run.

**Failure modes.**
- Unsigned skills must not appear in Hermes's runtime skill index. Enforcement is at Hermes's skill-loader, which queries ZP on startup and only loads `state == signed` skills.
- Rapid proposal spam → effectiveness-threshold gating + per-agent rate limit on proposals.
- Operator unavailable for long windows → `verification-pending` skills accumulate; the queue is the thing the operator catches up on, not individual decisions.

**Integration cost.** Adapter needed. Hermes currently writes skills to `~/.hermes/skills/` directly; requires a store-interposer in the skill toolchain.

---

## 4 · `ZPAdaptiveCapabilityQuarantine`

**Purpose.** When an agent or harness *creates* a new operational capability during execution — a DOM strategy written mid-task by browser-harness to route around a brittle selector, an inline helper function Hermes synthesizes, a schema inferred from a scrape — that capability does not silently become trusted infrastructure. It lands in quarantine as an unsigned artifact until reviewed and signed.

This is the interface the 2026-04-24 audit missed. Dispatch-time gates (Interface 2) govern *use*. `ZPSkillReceipt` (Interface 3) governs named skills. This interface governs *everything else that appears during execution and might want to persist*.

**Chokepoint.** Agent-side instrumentation. Hermes and Browser Harness both need to emit `QuarantineArtifact` events when they produce something that would outlive the current run. This is the new instrumentation — neither system emits these today.

**Artifact shape.**

```rust
pub struct QuarantineArtifact {
    pub artifact_id: Uuid,
    pub kind: ArtifactKind,            // DomStrategy | InlineHelper | Schema | Pattern | Other
    pub name: Option<String>,          // optional human-readable
    pub producer: String,              // "hermes" | "browser-harness" | "<tool_name>"
    pub produced_at: i64,
    pub thread_id: String,
    pub run_id: String,

    /// The artifact content itself, stored separately from the audit chain.
    /// The chain holds the hash; the blob store holds the content.
    pub content_hash: [u8; 32],
    pub content_location: String,      // path or object-store key

    /// Why the producer made this — the model's justification, if available.
    pub justification: String,

    /// Optional: the tool call that was being executed when this appeared,
    /// for provenance.
    pub during_tool_call: Option<Uuid>,
}
```

**Lifecycle.**

```
created  ──(auto-expire after N days)──►  expired
         ──(policy-triggered review)──►   review-pending
         ──(operator approves)──►         signed  →  (optionally)  promoted-to-skill
         ──(operator rejects)──►          rejected
```

Default policy: every `QuarantineArtifact` enters `created` state and is inaccessible to future runs unless `signed`. Artifacts expire after a retention window (default 14 days) if no review action is taken. Promotion to signed status may, at operator discretion, also emit a `SkillReceipt` (Interface 3) — folding the artifact into the named skill space.

**Query interface.**
- `GET /api/v1/quarantine` — list artifacts, filterable by state / kind / run.
- `GET /api/v1/quarantine/:id` — single artifact with content.
- `POST /api/v1/quarantine/:id/sign` — approve; artifact becomes referenceable by future runs.
- `POST /api/v1/quarantine/:id/reject` — reject; content deleted, receipt retained.
- `POST /api/v1/quarantine/:id/promote-to-skill` — sign + emit `SkillReceipt` in one action.

**Receipt types.**
- `QuarantineCreated` — emitted at artifact creation.
- `QuarantineSigned` / `QuarantineRejected` / `QuarantineExpired` — emitted at each terminal state.
- `QuarantinePromoted` — emitted when an artifact becomes a skill.

**Failure modes.**
- Agent bypasses quarantine by persisting artifacts outside the emission path → detected only at runtime when a future session loads an artifact not present in the signed set. Enforcement requires the agent's capability-load path to query ZP for the set of signed artifacts; unknown artifacts at load time are refused.
- Review queue saturation → per-kind rate limits on `QuarantineCreated`; past the limit, emissions are still recorded but the agent is notified to stop producing new artifacts of that kind.
- Content exfiltration risk in unsigned artifacts → artifacts classified as sensitive (containing credentials, PII) are stored encrypted at rest and only viewable by the signing operator.

**Integration cost.** Major surgery — requires instrumentation of both Hermes (skill-creation path, inline-helper synthesis) and Browser Harness (mid-task capability injection). Neither system exposes these events today. Deferred to Stage 3 of the transition plan.

---

## Composition

The four interfaces compose around a single run:

1. Run starts. AG-UI proxy obtains a `ZPBrowserExecutionEnvelope` if the run may touch the browser.
2. Hermes dispatches tools. Each dispatch passes through the `pre_tool_call_block_message` hook. If the tool is `memory_*`, it routes through `ZPMemoryProvider`. If it is `browser_*`, it is checked against the envelope.
3. Hermes may propose a new skill mid-run. It does not write to `~/.hermes/skills/`; it emits a `ZPSkillReceipt` in `proposed` state.
4. Browser Harness may synthesize a mid-task DOM strategy. It does not cache it locally; it emits a `QuarantineArtifact`.
5. Run ends. The audit chain now contains: tool-dispatch beads, memory-commit beads, browser-action beads, skill-proposal beads, quarantine-artifact beads — all on their respective wires, all drill-through from the abacus to the weave (who authorized) and the codeflow (how it derived).

No silent accumulation. No ambient authority. Every extension to what the system can do next is a separate, reviewable, signed decision.

---

## Staging

| Stage | Interfaces | Effort | Gates |
|---|---|---|---|
| 1 — Dispatch gate | `ZPBrowserExecutionEnvelope` (via plugin hook) | ~1 afternoon | What the system *does* |
| 2 — Artifact provenance | `ZPMemoryProvider` + `ZPSkillReceipt` | ~1 week | What the system *becomes* |
| 3 — Quarantine | `ZPAdaptiveCapabilityQuarantine` | ~2 weeks + instrumentation | What the system *accepts as its own* |

Build order matters. Stage 1 is low-cost and high-leverage: it governs existing capabilities without requiring any change to what Hermes or Browser Harness emit. Stages 2 and 3 require incremental instrumentation — Hermes's memory calls, skill writes, artifact production — but each addition closes one more axis along which the substrate could silently grow.

---

*A receipt is a decision about what the substrate chooses to become.*
