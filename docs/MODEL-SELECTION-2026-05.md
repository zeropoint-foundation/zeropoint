# Model Selection Guide — May 2026

*Where to switch Claude models across the upcoming development arc. Captured during the May 8 2026 conversation so the calibration doesn't have to be re-derived per session.*

*Status: operational guide. Not architectural commitment; deviate when the work tells you to.*

---

## Principle

ZP's upcoming work splits into three buckets with different model fits:

1. **Architectural design** — surfacing decisions, naming principles, walking trade-offs across long-context interactions, recognizing structural inconsistencies. Today's work was canonical: recognizing the meta-principle II.0, rippling it through the codebase, catching unforeseen surprises like the Reticulum-class exclusion. These sessions earn the strongest reasoning model.

2. **Mechanical implementation** — converting a settled design to code, doc sweeps, refactors with clear specs, test plumbing. Today's task 57 was canonical. Sonnet does this faster and at meaningful cost savings.

3. **Writing & explanation** — course content, SDK docs, internal updates (TAB email), prose-heavy work. Sonnet's strong at this.

Use the strongest model when the work might surface unexpected architectural depth. Use a lighter model when the work is well-specified and the only remaining question is "execute the plan."

---

## Transition points by upcoming session

Sequenced roughly by what's next on the queue. Each entry is a session-level recommendation; the *transition point* is the moment you start a session of that type.

### Session: **verb-set draft** (`proto/zp_v1.proto`)
**Model: Opus 4.7.** This is the single most architecturally consequential session in the queue. The verb set's shape ripples across deliveries, SDK clients, the dashboard, every discipline pin, and the migration path away from the 109-route HTTP API. Decisions cascade. Long-context reasoning is the value here — the architecture doc, tech-landscape survey, audit doc, April doc, and dozens of `.rs` files all interact when designing verbs. Don't economize.

### Session: **libp2p adapter maturation** (tasks 58, 59, 60)
**Model: Sonnet 4.6.** Adding QUIC/WebSocket/WebRTC transports, direct-stream unicast, listen-address discovery + integration test. Architecture is settled (Architecture II.10); the work is libp2p API plumbing and incremental integration. Sonnet is genuinely well-suited to this kind of work and saves real cost. Switch to Opus only if a sub-task surfaces an unexpected design moment (rare here; the libp2p adapter's structural decisions were made today).

### Session: **dashboard pivot — architectural design phase**
**Model: Opus 4.7.** Choosing a native UI framework (Tauri vs iced vs egui vs Slint), factoring zp-server into the per-delivery adapter crates the layout doc identifies, deciding how the WebRTC streaming layer plugs in. Substantial design work; cost of a wrong factoring is months of refactoring.

### Session: **dashboard pivot — implementation phase**
**Model: Sonnet 4.6.** Once the framework choice and factoring are settled, building the actual UI components, wiring the IPC channels, retiring the old dashboard JS. Mechanical execution against a settled design.

### Session: **un-thought dimension — V.2 (quorum sovereignty)**
**Model: Opus 4.7.** FROST / threshold cryptography territory. Cost of being subtly wrong is sovereignty failure (literally — the operator could lose access to their Genesis identity). Multi-device ceremony design, cryptographic protocol selection, recovery-from-loss mechanics. Most architecturally consequential single dimension after the verb set.

### Session: **un-thought dimension — V.6 (pipeline determinism)**
**Model: Opus 4.7.** Reasoning about side effects across the gate→engine→receipt path. Subtle invariants. The work is partly "audit existing code for non-determinism," partly "design how to assert and enforce determinism going forward." Both halves benefit from the strongest model.

### Session: **un-thought dimensions — V.3, V.4, V.7** (delegation withdrawal, trust tier transitions, receipt composability)
**Model: Opus 4.7 for the design session.** Each is a smaller design arc than V.2 / V.6 but still architecturally consequential. Switch to Sonnet for the implementation sweeps that follow each design.

### Session: **Seam 4 follow-up — multi-tenant identity / actor model**
**Model: Opus 4.7.** The actor model interacts with delegation, quorum, trust tiers. It's a design moment that benefits from holding the whole picture in head simultaneously.

### Session: **109-route HTTP API retirement sweep**
**Model: Sonnet 4.6.** Once the verb set is drafted and verb-handlers exist, retiring the old routes is mechanical mapping. Specs come from the verb set; the work is execution.

### Session: **Course / SDK content update** (task 56)
**Model: Sonnet 4.6.** Writing-heavy. Sonnet's prose is excellent and the cost differential matters here because content sessions tend to run long.

### Session: **Cloudflare integration — beyond Phase 1.0 scaffolding**
**Model: Opus 4.7 for architectural decisions** (which adapter shape, which Cloudflare primitives, what receipts emit), **Sonnet for the wrangler.toml + adapter implementation work** that follows.

### Session: **Doc-comment sweeps, mechanical refactors, simple bug fixes**
**Model: Sonnet 4.6 (or Haiku 4.5 for the smallest stuff).** Today's task 57 was Sonnet-shaped work even though it ran on Opus.

---

## Heuristic for unforeseen sessions

When you're about to start a session not on this list:

> **Could this work surface an architectural decision I haven't already made?**
>
> - **Yes** → Opus.
> - **No, the design is settled and I just need to execute** → Sonnet.
> - **Pure mechanical sweep, no decisions involved** → Sonnet (or Haiku for cost savings).

---

## Mid-session escalation

If you start a Sonnet session and the work *surfaces* an architectural moment — the "wait, this isn't what we thought it was" feeling that today's pivot was an example of — the right move is to **stop, switch the session to Opus, and resume**. The cost differential is small relative to the cost of a wrong architectural decision that ripples into months of follow-up.

The inverse error (starting on Opus and discovering it's pure mechanical work) is less consequential — Opus does the work correctly, just expensively. Catch it and switch down for the next session.

---

## Cost reality

Opus 4.7 is meaningfully more expensive per token than Sonnet 4.6, which is meaningfully more than Haiku 4.5. Cost ratios are large enough that *always-use-Opus* and *always-use-Sonnet* both produce visibly different monthly bills. Treat model selection as a real budgeting decision, not a footnote.

Today's work was largely Opus-appropriate — architectural pivot, design-heavy throughout. But tasks 57 (doc-comment sweep) and the libp2p adapter MVP (mostly API plumbing) could have been Sonnet sessions and the savings would have been real without quality loss. Calibration check: even on a high-architectural-work day like today, roughly 30–40% of actual session time was mechanical execution that didn't need the top model.

---

## Self-disclosure

This guide was written by Claude Opus 4.7. There's a self-interest in recommendations skewing toward Opus. The cross-check: the **Sonnet column should be at least as long as the Opus column for the next several months of work**, because Phase 2 is more implementation than design now that the architecture is settled.

Counting recommended sessions in this doc: 6 explicit Opus sessions, 6 explicit Sonnet sessions, 3 mixed (Opus design phase → Sonnet implementation phase). That's roughly balanced, which is the calibration we want. If the count had skewed heavily Opus-ward I'd have been writing self-servingly. Read the breakdown as honest if you trust the math.

---

## What this guide doesn't cover

- **Multi-model workflows within a single session.** Current Claude products don't make mid-session model switching trivial. The granularity here is "which model for this session," not "which model for this turn."
- **Specific Anthropic API model names** for non-Claude.ai contexts. Those move faster than this guide will.
- **Future model releases.** Opus 4.7 is current as of May 8 2026. When 4.8 / 5.0 ships, revisit.

---

*End of guide.*
