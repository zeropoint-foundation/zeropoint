# ZEROPOINT — Symphony Integration Architecture

## Governed Orchestration for Autonomous Coding Agents

**ThinkStream Labs** · May 2026 · Revision 1.0
**Document:** ZP-SYM-ARCH-001 · **Classification:** Internal / Strategic
**Companion specs:** Governed Agent Runtime (`governed-agent-runtime.md`), Hedera Grant Application (`HEDERA-GRANT-APPLICATION.md`), Formal Primitives (`FORMAL-PRIMITIVES.md`)
**External dependency:** [OpenAI Symphony SPEC.md](https://github.com/openai/symphony/blob/main/SPEC.md) (Apache 2.0)

---

> **Core Thesis:** Symphony solves coordination. ZeroPoint solves trust. An enterprise running 50 autonomous coding agents through Symphony can answer "what are they working on" but cannot answer "prove to me that agent-12 was authorized to do what it did, and that this proof hasn't been fabricated after the fact." The integration makes every Symphony state transition a governed event — cryptographically signed, hash-linked, and externally anchored.

> **Design Principle:** Symphony may orchestrate. ZeroPoint must witness. The receipt chain is the only thing that survives the agent.

---

## 1. Strategic Context

OpenAI's Symphony (released April 2026, Apache 2.0) defines a six-layer orchestration architecture that transforms issue trackers into control planes for coding agents. It treats each ticket as a state machine, spawns agents in isolated workspaces, monitors for stalls, retries failures, and coordinates concurrency — all without human supervision of individual sessions.

Symphony represents the maturation of what the AI engineering community calls "outer harness" design: the infrastructure that wraps around AI models to make them productive at scale. The spec distinguishes:

- **Inner harness** — built into the coding agent (Claude Code, Codex, Cursor): subagents, sandboxed execution, tool permissions, internal control flows.
- **Outer harness** — external code controlling session lifecycle, context injection, deterministic validation, and feedback loops.
- **Orchestrator** — the scheduler layer coordinating many agents and harnesses simultaneously.

ZeroPoint operates at the outer harness and orchestrator layers, but with a fundamentally different concern. Symphony asks: "How do we keep agents productive without humans becoming bottlenecks?" ZeroPoint asks: "How do we prove that what happened was authorized, bounded, and auditable?"

These are not competing concerns. They are complementary layers of the same stack.

---

## 2. The Governance Gap in Symphony

Symphony's spec (Section 9.5) defines three safety invariants:

1. Run the coding agent only in the per-issue workspace path.
2. Workspace path must stay inside workspace root.
3. Workspace key is sanitized.

These are filesystem containment rules — necessary but radically insufficient for enterprise governance. Symphony has no mechanism for:

- **Authorization provenance.** No proof that the agent was authorized to work on a given ticket. The orchestrator dispatches based on state matching, not cryptographic delegation.
- **Action auditing.** No tamper-evident record of what happened inside a session. The observability layer emits structured logs, but logs are mutable and unsigned.
- **Capability bounding.** No formal constraint on what the agent may do within its workspace. If the ticket says "fix the login bug," nothing prevents the agent from reading unrelated files, modifying CI configuration, or exfiltrating data through PR descriptions.
- **Human decision attestation.** When a human approves a PR, that approval exists in GitHub's database. It is not cryptographically linked to the agent's action chain, and cannot be independently verified without GitHub's cooperation.
- **Cross-session correlation.** If agent-7 and agent-12 work on related tickets, there is no governance chain connecting their actions to a shared authorization root.
- **Post-hoc verification.** An auditor arriving months later cannot reconstruct what happened with cryptographic certainty. They must trust that logs weren't modified, that GitHub's history is accurate, and that no agent exceeded its bounds undetected.

ZeroPoint closes every one of these gaps.

---

## 3. Integration Architecture

The integration operates at three levels, each independent and incrementally adoptable.

### 3.1 Level 1 — Hook-Based Receipt Emission

Symphony defines four workspace lifecycle hooks (Section 5.3.4):

| Hook | Timing | ZP Receipt Type |
|------|--------|-----------------|
| `after_create` | Workspace created for new issue | `orchestrator:workspace:created` |
| `before_run` | Before each agent attempt | `orchestrator:run:authorized` |
| `after_run` | After each agent attempt | `orchestrator:run:sealed` |
| `before_remove` | Before workspace deletion | `orchestrator:workspace:archived` |

**Implementation:** A `zp-symphony-hooks/` directory containing shell scripts that invoke `zp receipt emit` at each lifecycle boundary. The hooks are stateless — they read issue metadata from environment variables (set by Symphony) and emit signed receipts into the agent's per-issue chain.

```
hooks/
  after_create.sh    → zp receipt emit orchestrator:workspace:created
  before_run.sh      → zp receipt emit orchestrator:run:authorized
  after_run.sh       → zp receipt emit orchestrator:run:sealed
  before_remove.sh   → zp receipt emit orchestrator:workspace:archived
```

**Chain topology:** Each issue gets its own receipt chain. The chain's genesis receipt is emitted by `after_create` and references the operator's root genesis via `upstream_genesis`. This anchors the issue's entire history to the operator's identity — the agent working on ticket #347 is cryptographically bound to the organization that authorized the orchestrator.

**What this buys:** Tamper-evident lifecycle records. An auditor can verify that a workspace existed, that N attempts were made, and that the workspace was properly archived. This is Level 1 — no inner harness modification required.

### 3.2 Level 2 — Observer-Based Governance Stream

Symphony's Observability Layer (Section 6, Layer 6) emits structured events. The HTTP Server Extension (Section 13.7) exposes `/api/v1/state` and per-issue endpoints. A ZP observer process subscribes to these surfaces and translates Symphony events into governance receipts.

**Observer architecture:**

```
┌─────────────────────────────────────────────────┐
│                  Symphony Orchestrator           │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │ Agent 1 │  │ Agent 2 │  │ Agent N │        │
│  └────┬────┘  └────┬────┘  └────┬────┘        │
│       │             │             │             │
│  ┌────▼─────────────▼─────────────▼────┐       │
│  │         Observability Layer          │       │
│  └────────────────┬────────────────────┘       │
│                   │ structured events           │
└───────────────────┼─────────────────────────────┘
                    │
          ┌─────────▼─────────┐
          │   ZP Observer     │
          │                   │
          │  • Poll /api/v1/* │
          │  • Translate      │
          │  • Sign           │
          │  • Chain          │
          │  • Anchor         │
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │   ZP Chain Store  │
          │   (per-issue)     │
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │   Hedera HCS      │
          │   (epoch anchors) │
          └───────────────────┘
```

**Event mapping:**

| Symphony Event | ZP Receipt |
|----------------|------------|
| Issue dispatched | `orchestrator:issue:dispatched` |
| State: Unclaimed → Claimed | `orchestrator:issue:claimed` |
| State: Claimed → Running | `agent:session:started` |
| Run phase: PreparingWorkspace | `agent:workspace:prepared` |
| Run phase: BuildingPrompt | `agent:prompt:rendered` |
| Run phase: StreamingTurn | `agent:turn:N` (per turn) |
| Run phase: Succeeded | `agent:run:succeeded` |
| Run phase: Failed | `agent:run:failed` |
| Run phase: TimedOut | `agent:run:timed_out` |
| Run phase: Stalled | `agent:run:stalled` |
| State: Running → RetryQueued | `orchestrator:retry:scheduled` |
| State: * → Released | `orchestrator:issue:released` |
| Human approval (via Linear) | `human:review:approved` |
| PR merged (via webhook) | `orchestrator:pr:landed` |

**What this buys:** Fine-grained, tamper-evident audit trail of every state transition, turn, and human decision — without modifying Symphony's code. The observer is a sidecar that reads events and writes receipts.

### 3.3 Level 3 — Governance Gate Integration

At the deepest level, ZeroPoint becomes a policy authority that Symphony consults before dispatching. This requires a custom tracker adapter or a middleware between Symphony and Linear.

**Gate flow:**

```
Symphony fetch_candidate_issues()
  → ZP gate: Does this agent have capability to work on this issue?
  → ZP gate: Is the issue's label set within the agent's authorized scope?
  → ZP gate: Has the concurrency budget for this trust tier been exceeded?
  → If all pass: dispatch with capability receipt
  → If any fail: skip, emit orchestrator:issue:blocked receipt
```

**Capability model:**

Each agent (or agent pool) gets a `CapabilityGrant` receipt at canonicalization time that defines:

- **Scope:** Which Linear labels, projects, or issue types this agent may work on.
- **Authority:** What filesystem operations, network calls, and tool invocations are permitted.
- **Budget:** Maximum turns per issue, maximum concurrent issues, cost ceiling.
- **Delegation chain:** Who authorized this agent, traceable back to the operator genesis.

The governance gate checks the capability grant against the issue metadata before allowing dispatch. This is the constitutional layer — an agent cannot work on a ticket outside its granted scope, regardless of what Symphony's state machine would otherwise allow.

**What this buys:** Principle of least privilege for autonomous agents. Proof that every dispatch was authorized. Capability-based access control that survives the agent process and is independently verifiable.

---

## 4. Chain Topology

### 4.1 Per-Issue Chains

Each issue gets its own receipt chain:

```
orchestrator:workspace:created      ← genesis (refs operator root)
  └→ orchestrator:run:authorized    ← attempt 1
       └→ agent:turn:1
       └→ agent:turn:2
       └→ agent:turn:3
       └→ orchestrator:run:sealed   ← attempt 1 complete (failed)
  └→ orchestrator:retry:scheduled
  └→ orchestrator:run:authorized    ← attempt 2
       └→ agent:turn:1
       └→ agent:turn:2
       └→ orchestrator:run:sealed   ← attempt 2 complete (succeeded)
  └→ orchestrator:pr:landed
  └→ human:review:approved
  └→ orchestrator:issue:released
  └→ orchestrator:workspace:archived  ← chain sealed
```

### 4.2 Orchestrator Meta-Chain

A separate chain tracks the orchestrator itself:

```
orchestrator:genesis                ← operator genesis reference
  └→ orchestrator:config:loaded     ← WORKFLOW.md hash
  └→ orchestrator:started           ← timestamp, version
  └→ orchestrator:tick:N            ← periodic heartbeat
  └→ orchestrator:issue:dispatched  ← cross-ref to per-issue chain
  └→ orchestrator:issue:dispatched  ← ...
  └→ orchestrator:epoch:sealed      ← periodic Merkle seal
```

### 4.3 Epoch Anchoring

Per the Hedera integration design, epoch boundaries trigger external anchoring:

- Every N minutes (configurable, default 15), the orchestrator meta-chain is epoch-sealed.
- The epoch's Merkle root is submitted to Hedera HCS.
- Per-issue chains are included in the epoch Merkle tree.
- This means an auditor can prove that a given issue chain existed at a specific time, using only the Hedera mirror node — no cooperation from the operator required.

---

## 5. Implementation Plan

### Phase 1: Hook-Based (Level 1) — 2 weeks

**Deliverables:**
- `zp-symphony-hooks/` directory with four shell scripts
- Chain genesis logic: create per-issue chain with upstream reference
- `zp receipt emit` CLI support for orchestrator receipt types
- Documentation: how to configure Symphony's `hooks.*` section

**Validation:** Run Symphony with hooks against a test Linear project. Verify `zp verify` passes on the resulting chains. Verify upstream reference resolves to operator genesis.

### Phase 2: Observer Sidecar (Level 2) — 3 weeks

**Deliverables:**
- `zp-symphony-observer` binary (Rust, single-binary deployment)
- Polls Symphony HTTP API at configurable interval
- Translates events to typed receipts
- Signs with operator key
- Appends to per-issue chains
- Emits `orchestrator:tick` heartbeats to meta-chain

**Validation:** Run observer alongside Symphony. Verify complete event coverage — every Symphony state transition has a corresponding receipt. Verify `zp verify` on all chains. Load test with 10 concurrent agents.

### Phase 3: Governance Gate (Level 3) — 4 weeks

**Deliverables:**
- `CapabilityGrant` receipt type for agent pools
- Gate middleware (intercepts between Symphony and Linear API)
- Policy language for scope/authority/budget constraints
- `zp symphony status` CLI showing live agent authorization state
- Dashboard panel: which agents are working on what, with governance state

**Validation:** Attempt to dispatch an agent outside its capability scope — verify blocked. Attempt to exceed concurrency budget — verify blocked. Verify all blocks emit receipts. Verify dashboard reflects live state.

### Phase 4: Hedera Anchoring — 2 weeks (concurrent with Phase 2–3)

**Deliverables:**
- Epoch sealing on orchestrator meta-chain
- Per-issue chain inclusion in epoch Merkle tree
- HCS submission of epoch roots
- Verification surface: given a receipt, prove its inclusion in an anchored epoch

**Validation:** Anchor 100 issue chains over 24 hours. Verify any single receipt can be independently verified via Hedera mirror node query.

---

## 6. Competitive Positioning

### 6.1 What Exists Today

| System | Coordination | Trust |
|--------|-------------|-------|
| Symphony (OpenAI) | Ticket-driven orchestration | Filesystem sandboxing only |
| Gas Town | Parallel Ralph Wiggum loops | None |
| Archon | Multi-agent orchestration | None |
| Microsoft AGT | In-process governance hooks | Dies with the process |
| GitHub Actions | CI/CD pipeline | Platform-dependent audit logs |

### 6.2 What ZeroPoint + Symphony Provides

- **Coordination:** Symphony's battle-tested orchestration (polling, retry, concurrency, stall detection)
- **Trust:** ZeroPoint's cryptographic governance (signed receipts, hash-linked chains, capability bounds)
- **Anchoring:** Hedera's external witness (epoch Merkle roots on public ledger)
- **Portability:** Trust evidence survives the orchestrator, the agent, and the platform

### 6.3 The Pitch

"You're running 50 agents landing PRs autonomously. Congratulations — you've solved productivity. Now your CISO asks: can you prove that agent-12 was authorized to modify the auth module, that it didn't access the payments codebase, and that this proof wasn't fabricated after the incident? Symphony + ZeroPoint + Hedera: yes, here's the chain, here's the Merkle root, here's the HCS timestamp. Verify it yourself."

---

## 7. Relationship to Existing ZeroPoint Architecture

### 7.1 GAR Reuse

The Governed Agent Runtime (GAR) already implements:
- Canonicalization (agents get cryptographic identity)
- Capability-based authorization (governance gate)
- Receipt emission at dispatch boundaries
- Epoch sealing and Merkle anchoring

The Symphony integration is a new *surface* for existing *primitives*. The `zp-symphony-observer` is structurally identical to the IronClaw observation pipeline — it watches an agent framework's events and translates them to ZP receipts. The governance gate is the same gate, with a new policy evaluation context (Linear issue metadata instead of MCP tool calls).

### 7.2 New Primitives Required

| Primitive | Status | Notes |
|-----------|--------|-------|
| Per-issue chain genesis | New | Lightweight chain creation with upstream ref |
| Orchestrator meta-chain | New | Heartbeat + dispatch cross-references |
| `CapabilityGrant` for agent pools | Extension | Existing CapabilityGrant, new scope vocabulary |
| Hook-based receipt emission | New CLI surface | `zp receipt emit` from shell |
| Observer sidecar pattern | Reusable | Same pattern as IronClaw observer |

### 7.3 Hedera Grant Alignment

The Hedera grant application proposes five deliverables. The Symphony integration strengthens deliverables 2 (runtime integration) and 4 (live verification surface) by providing a concrete, compelling demo scenario:

> "Here are 50 autonomous agents landing real PRs. Every action is receipted. Every epoch is anchored to Hedera. Verify any agent's work using only a mirror node query."

This is more compelling than an abstract "receipt chain anchored to HCS" demo because it shows governance at scale — the exact scenario enterprises face as they adopt Symphony-style orchestration.

---

## 8. Open Questions

1. **Inner harness instrumentation.** Level 1–3 operate at the outer harness and orchestrator layers. Should we also instrument what happens inside the agent session? This would require Codex/Claude Code to emit structured events that the observer can capture. Claude Code's `--output-format stream-json` may already provide this.

2. **Multi-orchestrator topology.** If an enterprise runs multiple Symphony instances (per-team, per-repo), should they share a single operator genesis or have per-orchestrator chains? Recommendation: per-orchestrator chains with shared root genesis, matching fleet topology.

3. **Tracker adapter generality.** Symphony currently targets Linear. The integration should be tracker-agnostic at the ZP layer — receipts reference issue identifiers, not Linear-specific concepts. This positions ZP to work with Jira, GitHub Issues, or any future tracker adapter Symphony supports.

4. **Cost attribution.** Symphony tracks agent turns and can enforce `max_turns`. Should ZP receipts include token usage data for cost attribution? This would enable governance-level budget enforcement independent of Symphony's internal limits.

5. **PR content verification.** When an agent opens a PR, should ZP hash the PR diff and include it in the receipt? This would cryptographically bind the governance chain to the actual code change, preventing post-hoc PR amendment without breaking the chain.

---

## 9. Summary

Symphony is the best-designed public orchestration spec for coding agents. It handles coordination, concurrency, retry, and lifecycle management with mature engineering (OTP supervision trees, deterministic state machines, hook-based extensibility). What it does not handle — and explicitly does not claim to handle — is trust.

ZeroPoint provides trust as a layer that Symphony can adopt incrementally:

- **Level 1 (hooks):** Drop-in shell scripts. Zero modification to Symphony. Tamper-evident lifecycle records.
- **Level 2 (observer):** Sidecar binary. Full event coverage. Fine-grained audit trail.
- **Level 3 (gate):** Policy authority. Capability-based dispatch. Constitutional constraints on autonomous agents.

Each level is independently valuable. An enterprise can start with hooks today and upgrade to full governance as their compliance requirements demand. The chain is backward-compatible — Level 2 receipts extend Level 1 chains, Level 3 gates reference Level 2 observations.

This is ZeroPoint's value proposition crystallized: we don't compete with the orchestrator. We make the orchestrator trustworthy.

---

*Sources: [OpenAI Symphony SPEC.md](https://github.com/openai/symphony/blob/main/SPEC.md), [OpenAI Symphony announcement](https://openai.com/index/open-source-codex-orchestration-symphony/), [Symphony GitHub repository](https://github.com/openai/symphony)*
